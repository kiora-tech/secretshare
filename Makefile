# Tout passe par Docker : ni PHP ni Node sur le poste.
PHP = docker exec secretshare_php
E2E_IMAGE = mcr.microsoft.com/playwright/python:v1.51.0-noble

.PHONY: up down sf test e2e qa purge

up: ## Démarre la stack locale sur http://localhost:18108 et applique les migrations
	docker compose up -d postgres php nginx
	docker compose run --rm migrations

down:
	docker compose down

sf: ## make sf c="debug:router"
	$(PHP) php bin/console $(c)

test: ## PHPUnit (unitaires + fonctionnels sur la base secretshare_test)
	docker exec -e APP_ENV=test secretshare_php sh -c 'php bin/console doctrine:database:create --if-not-exists -q && php bin/console doctrine:migrations:migrate -n -q && php vendor/bin/phpunit --testdox'

e2e: ## Parcours complets dans Chromium (chiffrement, lecture unique, demande post-quantique)
	# Les limites de débit s'appliquent en dev aussi : on repart de compteurs vides.
	$(PHP) php bin/console dbal:run-sql -q "TRUNCATE cache_items"
	mkdir -p var/e2e && chmod 777 var/e2e
	docker run --rm --network host -v "$(CURDIR)/tests/e2e:/e2e:ro" -v "$(CURDIR)/var/e2e:/out" $(E2E_IMAGE) \
		sh -c 'pip install -q playwright==1.51.0 >/dev/null 2>&1; python /e2e/e2e.py http://localhost:18108 /out'

qa: ## PHPStan + style
	$(PHP) php vendor/bin/phpstan analyse --no-progress --memory-limit=512M
	$(PHP) php vendor/bin/php-cs-fixer fix --dry-run --diff

purge:
	$(PHP) php bin/console app:purge
