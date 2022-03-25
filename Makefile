

run-example:
	@docker-compose up --build

restart-example:
	@while true; do docker-compose restart app1; sleep 4; docker-compose restart app2; sleep 4; done
