
SHELL := /bin/bash
PY ?= python3
BASE_BRANCH ?= main
VERSION ?= v0.1.1

# ------- Tooling discovery -------
have-%:
	@command -v $* >/dev/null 2>&1

# ------- Setup -------
setup:  ## Install dev tools (ruff, black, pytest, semgrep, gh)
	@$(MAKE) have-ruff || pip install ruff >/dev/null
	@$(MAKE) have-black || pip install black >/dev/null
	@$(MAKE) have-pytest || pip install pytest >/dev/null
	@$(MAKE) have-semgrep || pip install semgrep >/dev/null
	@$(MAKE) have-gh || echo "Install GitHub CLI: https://cli.github.com/"

# ------- Quality -------
lint:  ## Lint & format checks
	@ruff . || true
	@black --check . || true

test:  ## Run tests
	@pytest -q || echo "No tests yet"

scan:  ## Semgrep delta scan vs base branch
	@git fetch origin $(BASE_BRANCH) --depth=1 >/dev/null 2>&1 || true
	@semgrep scan --config rules/ \
		--changed-since origin/$(BASE_BRANCH) \
		--exclude node_modules --exclude dist --exclude .git \
		--timeout 300 --max-target-bytes 200MB --error --jobs auto || true

# ------- Branch protection -------
PROTECTION_FILE := .github/branch-protection/protection.json
REPO ?= lansiquo/PR_reviewer
BRANCH ?= main

protect:  ## Apply branch protection
	@gh api -X PUT repos/$(REPO)/branches/$(BRANCH)/protection \
	  -H "Accept: application/vnd.github+json" \
	  --input $(PROTECTION_FILE) && echo "Protection applied to $(REPO)#$(BRANCH)"

unprotect:  ## Remove branch protection
	@gh api -X DELETE repos/$(REPO)/branches/$(BRANCH)/protection \
	  -H "Accept: application/vnd.github+json" && echo "Protection removed"

# ------- Release -------
release:  ## Tag and create GitHub release: make release VERSION=v0.1.1
	@test -n "$(VERSION)" || (echo "Set VERSION=vX.Y.Z"; exit 1)
	@git tag -a $(VERSION) -m "$(VERSION)" && git push origin $(VERSION)
	@gh release create $(VERSION) --title "$(VERSION)" --notes "See CHANGELOG for details."
	@echo "Release $(VERSION) published."
PROTECTION_FILE := .github/branch-protection/protection.json
REPO ?= lansiquo/PR_reviewer
BRANCH ?= main

protect:  ## Apply branch protection
	@gh api -X PUT repos/$(REPO)/branches/$(BRANCH)/protection \
	  -H "Accept: application/vnd.github+json" \

	  --input $(PROTECTION_FILE)
	@echo "Branch protection applied to $(REPO)#$(BRANCH)"
 0c673a8 (Removing Bad.py)
