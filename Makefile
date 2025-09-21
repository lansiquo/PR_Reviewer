PROTECTION_FILE := .github/branch-protection/protection.json
REPO := lansiquo/PR_reviewer
BRANCH := main

protect:
	@gh api -X PUT repos/$(REPO)/branches/$(BRANCH)/protection \
	  -H "Accept: application/vnd.github+json" --input $(PROTECTION_FILE)
	@echo "Protection applied"

unprotect:
	@gh api -X DELETE repos/$(REPO)/branches/$(BRANCH)/protection \
	  -H "Accept: application/vnd.github+json" && echo "Protection removed"

protect-solo:
	@jq '.required_pull_request_reviews=null' $(PROTECTION_FILE) > /tmp/p.json && \
	mv /tmp/p.json $(PROTECTION_FILE) && $(MAKE) protect
