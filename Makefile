# DEBUG := -x
.DEFAULT_GOAL := lambda-zip

.PHONY: help
help:
	@-echo
	@-echo "  GIT_BRANCH is ${GIT_BRANCH} and GIT_NAME is ${GIT_NAME}"
	@-echo
	@-echo "  make lambda-zip   - zip all files needed for the lambda"
	@-echo

.PHONY: lambda-zip
lambda-zip:
	zip -R aha-`cat VERSION`.zip *.py
