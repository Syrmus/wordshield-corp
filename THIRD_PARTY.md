# Third-party components

The MIT license in this repository covers original WordShield code and
documentation, not third-party models, packages, container base images or
system software. These are obtained separately; retain their license notices
and meet their terms when building or distributing an installation or image.
Dependency manifests are in `pyproject.toml` and `deploy/corp/requirements-*.txt`;
the Dockerfile also installs system packages. This is not a complete legal
review or a transitive dependency license inventory.

## Models (checked 2026-10-11)

- [vladlinv/ru-pii-ner-gliner2.5](https://huggingface.co/vladlinv/ru-pii-ner-gliner2.5),
  revision `7ed92ea48f59ca7044ecde89f9c802fe63d360ee`: model metadata declares
  Apache-2.0. Consult upstream terms and base-model notices before redistribution.
- [apararti/privacy-filter-ru](https://huggingface.co/apararti/privacy-filter-ru),
  revision `a1650a1927ed8aceb9e15fa8ed13ffdf60cbf107`: no license declaration in
  model metadata and no LICENSE file in the revision's file listing were found.
  **Rights to use and redistribute these fine-tuned weights must be clarified
  with their publisher before corporate deployment or redistribution.** Do not
  assume the base model's license grants rights to the fine-tune. Publication
  of WordShield source under MIT does not resolve this question.
- [OpenAI Privacy Filter runtime](https://github.com/openai/privacy-filter):
  separately installed at the revision pinned in requirements-models.txt;
  its upstream license and notices continue to apply.

No model weights are distributed in this Git repository. Existing model
configuration is unchanged; no replacement model is silently substituted.
