.PHONY: test demo benchmark init-hydradb docker-boot-test

test:
	PYTHONPATH=backend python -m unittest discover -s tests -v

demo:
	PYTHONPATH=backend python -m hydrashield.api --demo

benchmark:
	PYTHONPATH=backend python scripts/benchmark.py

init-hydradb:
	mkdir -p hydradb-data/store hydradb-data/cache
	printf '%s\n' 'local-development-token-32-bytes' > hydradb-data/auth-token

docker-boot-test:
	bash scripts/docker_boot_test.sh
