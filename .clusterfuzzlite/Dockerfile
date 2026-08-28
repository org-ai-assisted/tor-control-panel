## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ClusterFuzzLite Python Dockerfile.
## https://google.github.io/clusterfuzzlite/build-integration/python-lang/

## Image: gcr.io/oss-fuzz-base/base-builder-python.
##
## Trust root - this image path is the canonical Python base for
## OSS-Fuzz / ClusterFuzzLite, published by Google's OSS-Fuzz
## project. The Dockerfile that produces this image lives in the
## OSS-Fuzz repo; the language-specific guide tells integrators to
## use this exact path:
##   https://github.com/google/oss-fuzz/tree/master/infra/base-images/base-builder-python
##   https://google.github.io/oss-fuzz/getting-started/new-project-guide/python-lang/
##
## :latest stays matched to clusterfuzzlite-run-fuzzers:v1's ABI
## (Ubuntu 20.04 / glibc 2.31) - OSS-Fuzz keeps this guarantee so
## binaries built in the base-builder land cleanly in the run
## container. Do not pin to the ubuntu-24-04 tag without also
## forking CFLite to override its hardcoded run image. Digest kept in
## sync with the other packages' .clusterfuzzlite Dockerfiles.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:9dd557a4ba0e0cdfbeabc0bb115c98896f2dab68c3e8f301abf169469b8b5ef5

COPY . $SRC/tor-control-panel

## tor-control-panel's config logic imports sanitize_string from helper-scripts,
## so make a helper-scripts checkout importable in the harnesses. Tracked at
## master, not pinned: the trust boundary here is the org account, not the ref,
## and branch-tracking is what lets an upstream fix reach every consumer
## without a bump PR per repo (github-actions.md G-A-004).
RUN git clone --depth=1 https://github.com/Kicksecure/helper-scripts \
      $SRC/helper-scripts

COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/tor-control-panel
