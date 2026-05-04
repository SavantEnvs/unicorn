# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder
RUN sed -i "s|http://archive.ubuntu.com/ubuntu|http://us.archive.ubuntu.com/ubuntu|g; s|http://security.ubuntu.com/ubuntu|http://us.archive.ubuntu.com/ubuntu|g" /etc/apt/sources.list && apt-get update && apt-get install -y cmake pkg-config make python3
COPY . unicorn
RUN rm -rf unicorn/mayhem
WORKDIR $SRC
COPY mayhem/build.sh $SRC/

ENV FUZZING_LANGUAGE=c++ SANITIZER=address
RUN compile
