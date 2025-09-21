PROTECTION_FILE := .github/branch-protection/protection.json
REPO := lansiquo/PR_reviewer
BRANCH := main

protect:
	@gh api -X PUT repos/$(REPO)/branches/$(BRANCH)/protection \
	  -H "Accept: application/vnd.github+json" \
	  --input $(PROTECTION_FILE)
	@echo "Branch protection applied to $(REPO)#$(BRANCH)"
