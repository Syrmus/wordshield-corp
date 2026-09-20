import asyncio
from types import SimpleNamespace
import pytest
from wordshield.gliner_detector import inference_timeout, worker_response
from wordshield.detectors import DetectorUnavailable


def test_timeout_scales_and_is_bounded():
    assert inference_timeout([SimpleNamespace(text='x' * 20)]) == 180
    assert inference_timeout([SimpleNamespace(text='x' * 20000)]) == 620
    assert inference_timeout([SimpleNamespace(text='x' * 100000)]) == 1200


def test_worker_errors_are_actionable():
    async def run():
        reader = asyncio.StreamReader()
        process = SimpleNamespace(stdout=reader)
        with pytest.raises(DetectorUnavailable, match='Запуск.*время ожидания'):
            await worker_response(process, .001, 'Запуск')
        reader.feed_eof()
        with pytest.raises(DetectorUnavailable, match='процесс детектора завершился'):
            await worker_response(process, 1, 'Обработка')
    asyncio.run(run())


def test_worker_success():
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b'{"ready":true}\n')
        assert await worker_response(SimpleNamespace(stdout=reader), 1, 'Запуск') == {'ready': True}
    asyncio.run(run())
