from __future__ import annotations
import asyncio
import json
import os
import sys
from pathlib import Path
from .models import Detection, inference_view, map_detection
from .detectors import DetectorUnavailable


def inference_timeout(blocks):
    # CPU Privacy Filter processes multiple token windows inside one request.
    # Bound waiting, but do not give a whole long contract the short-block limit.
    return min(1200, max(180, 120 + sum(len(b.text) for b in blocks) / 40))


async def worker_response(process, timeout, phase):
    try:
        line = await asyncio.wait_for(process.stdout.readline(), timeout)
    except TimeoutError as exc:
        raise DetectorUnavailable(
            f"{phase}: превышено время ожидания ({round(timeout / 60)} мин). Можно продолжить анализ."
        ) from exc
    if not line:
        raise DetectorUnavailable(f"{phase}: процесс детектора завершился. Можно продолжить анализ.")
    return json.loads(line)


class GlinerDetector:
    mode = "gliner"
    def __init__(self, settings):
        self.settings = settings
        self.process = None
        self.lock = asyncio.Lock()

    async def _start(self):
        if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists():
            raise DetectorUnavailable("Локальный детектор требует системную изоляцию сети macOS")
        worker = str(Path(__file__).with_name("local_worker.py"))
        # macOS refuses applying a different nested sandbox. An inherited
        # application policy is acceptable only with the worker's active OS
        # denial probe, which runs before it receives document text.
        sandbox = [] if os.getenv("WORDSHIELD_INHERIT_NETWORK_SANDBOX") == "1" else [
            "/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network*)"]
        self.process = await asyncio.create_subprocess_exec(
            *sandbox,
            (self.settings.gliner_python if self.mode == "gliner" else self.settings.privacy_python) or sys.executable,
            worker, self.settings.gliner_checkpoint if self.mode == "gliner" else self.settings.privacy_checkpoint, self.mode,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            env={**os.environ, "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1"},
            limit=16*1024*1024,
        )
        ready = await worker_response(self.process, 600, 'Запуск локальной модели')
        if not ready.get("ready") or not ready.get("network_denied"):
            raise DetectorUnavailable("Локальный детектор не прошёл проверку изоляции")

    async def close(self):
        if self.process:
            if self.process.returncode is None:
                self.process.kill()
            await self.process.wait()
            self.process = None

    async def detect(self, blocks, completed=None, on_chunk=None):
        async with self.lock:
            try:
                if self.process is None or self.process.returncode is not None:
                    await self._start()
                found = []
                for block in blocks:
                    if not block.text or block.id in (completed or set()):
                        continue
                    view, _ = inference_view(block)
                    payload = {"blocks": [{"id": block.id, "text": view.text}], "threshold": self.settings.gliner_threshold}
                    self.process.stdin.write((json.dumps(payload, ensure_ascii=False)+"\n").encode())
                    await self.process.stdin.drain()
                    result = await worker_response(self.process, inference_timeout([block]), 'Проверка русского текста')
                    if "error" in result:
                        raise DetectorUnavailable("Ошибка локального русского детектора")
                    chunk = [Detection(**d) for d in result["detections"]]
                    if any(d.block_id != block.id or not 0 <= d.start < d.end <= len(view.text)
                           or view.text[d.start:d.end] != d.exact_text for d in chunk):
                        raise DetectorUnavailable("GLiNER: несовпадение диапазонов")
                    chunk = [mapped for d in chunk for mapped in map_detection(block, d)]
                    found.extend(chunk)
                    if on_chunk:
                        on_chunk([block], chunk)
                return found
            except BaseException:
                await self.close()
                raise


class SandboxedPrivacyDetector(GlinerDetector):
    mode = "privacy"

    async def detect(self, blocks, completed=None, on_chunk=None):
        async with self.lock:
            try:
                if self.process is None or self.process.returncode is not None:
                    await self._start()
                from .detectors import privacy_chunks
                found = []
                for chunk in privacy_chunks(blocks):
                    if all(b.id in (completed or set()) for b in chunk):
                        continue
                    views = {b.id: inference_view(b)[0] for b in chunk}
                    payload = {"blocks": [{"id": b.id, "text": views[b.id].text} for b in chunk]}
                    self.process.stdin.write((json.dumps(payload, ensure_ascii=False)+"\n").encode())
                    await self.process.stdin.drain()
                    result = await worker_response(self.process, inference_timeout(chunk), 'Поиск персональных данных')
                    if "error" in result:
                        raise DetectorUnavailable("Ошибка локального Privacy Filter")
                    by_id = {b.id: b for b in chunk}
                    ds = [Detection(**d) for d in result["detections"]]
                    if any(d.block_id not in views or not 0 <= d.start < d.end <= len(views[d.block_id].text)
                           or views[d.block_id].text[d.start:d.end] != d.exact_text for d in ds):
                        raise DetectorUnavailable("Privacy Filter: несовпадение диапазонов")
                    ds = [mapped for d in ds for mapped in map_detection(by_id[d.block_id], d)]
                    found.extend(ds)
                    if on_chunk:
                        on_chunk(chunk, ds)
                return found
            except BaseException:
                await self.close()
                raise
