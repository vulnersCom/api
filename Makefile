format:
	poetry run ruff format vulners
	poetry run ruff format samples

isort:
	poetry run ruff check --select I --fix vulners
	poetry run ruff check --select I --fix samples

mypy:
	poetry run mypy vulners

mypy-one:
	poetry run mypy ${ARGS}

cc:
	make format
	make isort
