HTTP_BUILD_DIR := $(BUILD_DIR)/tests/http

#
#  Test name
#
TEST      := test.http
TEST_LIBS := libfreeradius-http$(L) proto_http$(L) proto_http_tcp$(L) process_http$(L)
FILES     := $(subst $(DIR)/,,$(wildcard $(DIR)/*.txt))

$(eval $(call TEST_BOOTSTRAP))

#
#  Config settings
#
HTTP_BUILD_DIR  := $(BUILD_DIR)/tests/http
HTTP_RADIUS_LOG := $(HTTP_BUILD_DIR)/radiusd.log
HTTP_GDB_LOG    := $(HTTP_BUILD_DIR)/gdb.log

#
#  Generic rules to start / stop the radius service.
#
include src/tests/radiusd.mk
$(eval $(call RADIUSD_SERVICE,radiusd,$(OUTPUT)))

#
#  Run a test against the running radiusd and compare output.
#
#  Tests may use either:
#    ARGV: <curl arguments>   — sends a request via curl
#    CMD:  <shell command>    — runs an arbitrary shell command (for raw TCP tests
#                               that curl cannot produce, e.g. malformed headers)
#
#  In CMD lines, PORT is substituted with the actual test port just like ARGV.
#  CMD output is compared to the .out file byte-for-byte, same as ARGV tests.
#
$(OUTPUT)/%: $(DIR)/% $(BUILD_DIR)/lib/libfreeradius-http.la $(BUILD_DIR)/lib/process_http.la | $(TEST).radiusd_kill $(TEST).radiusd_start
	$(eval TARGET   := $(notdir $<))
	$(eval EXPECTED := $(patsubst %.txt,%.out,$<))
	$(eval FOUND    := $(patsubst %.txt,%.out,$@))
	$(eval ARGV     := $(shell sed -n 's/^#.*ARGV: //p' $< | sed 's/PORT/$(http_port)/g'))
	$(eval CMD      := $(shell sed -n 's/^#.*CMD: //p' $<  | sed 's/PORT/$(http_port)/g'))
	$(eval HAS_CMD  := $(if $(CMD),yes,no))
	${Q}echo "HTTP-TEST INPUT=$(TARGET)"
	${Q}[ -f $(dir $@)/radiusd.pid ] || exit 1
	${Q}if [ "$(HAS_CMD)" = "yes" ]; then \
		if ! $(CMD) > $(FOUND) 2>&1; then \
			echo "FAILED";                                          \
			cat $(FOUND);                                           \
			rm -f $(BUILD_DIR)/tests/test.http;                     \
			$(MAKE) --no-print-directory test.http.radiusd_kill;    \
			echo "RADIUSD: $(RADIUSD_RUN)";                         \
			echo "CMD: $(CMD)";                                     \
			exit 1;                                                 \
		fi; \
	else \
		if ! curl $(ARGV) > $(FOUND) 2>&1; then \
			echo "FAILED";                                          \
			cat $(FOUND);                                           \
			rm -f $(BUILD_DIR)/tests/test.http;                     \
			$(MAKE) --no-print-directory test.http.radiusd_kill;    \
			echo "RADIUSD: $(RADIUSD_RUN)";                         \
			echo "CURL: curl $(ARGV)";                              \
			exit 1;                                                 \
		fi; \
	fi
	${Q}if [ -e "$(EXPECTED)" ] && ! cmp -s $(FOUND) $(EXPECTED); then \
		echo "HTTP-TEST FAILED $@";                             \
		echo "RADIUSD: $(RADIUSD_RUN)";                         \
		echo "CMD: $(if $(CMD),$(CMD),curl $(ARGV))";           \
		echo "ERROR: File $(FOUND) is not the same as $(EXPECTED)"; \
		echo "If you updated proto_http code, update the expected output."; \
		echo "e.g: $(EXPECTED)";                                \
		diff $(EXPECTED) $(FOUND);                              \
		rm -f $(BUILD_DIR)/tests/test.http;                     \
		$(MAKE) --no-print-directory test.http.radiusd_kill;    \
		exit 1;                                                 \
	fi
	${Q}touch $@

$(TEST):
	${Q}$(MAKE) --no-print-directory $@.radiusd_stop
	@touch $(BUILD_DIR)/tests/$@
