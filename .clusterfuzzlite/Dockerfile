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
## so make a helper-scripts checkout importable in the harnesses.
##
## Pinned to an immutable commit, not a branch tip: this is a CROSS-org
## dependency (Kicksecure, not org-ai-assisted) whose code is executed inside
## the fuzzing image, so a later upstream push must not change what this repo
## runs without a reviewed change here. Bump deliberately.
RUN git clone https://github.com/Kicksecure/helper-scripts $SRC/helper-scripts \
      && git -C $SRC/helper-scripts checkout --quiet \
         3b3a8dd96d33d107fc9450a14172af94529e6f21

COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/tor-control-panel
