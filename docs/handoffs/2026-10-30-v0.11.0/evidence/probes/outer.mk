.PHONY: all inner
all:
	$(MAKE) -f /home/katsumata-m/secdat-release-evidence/v0.11.0/probes/outer.mk inner
inner:
	@bash /home/katsumata-m/secdat-release-evidence/v0.11.0/probes/query.sh
