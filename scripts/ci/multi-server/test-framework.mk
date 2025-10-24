PHONY_TARGETS += test-framework test.test-framework
.PHONY: $(PHONY_TARGETS)

test-framework:
	@python3 scripts/ci/multi-server/multi_server_test.py $(filter-out $(PHONY_TARGETS),$(MAKECMDGOALS))
	echo "Multi-server test framework completed."

test.test-framework: test-framework

# Dummy targets to avoid "No rule to make target" errors
%:
	@:
