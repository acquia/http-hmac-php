.PHONY: install clean test coverage update format

install:
	composer install --no-interaction

clean:
	rm -rf vendor/ dist/ composer.lock .php_cs.cache .phpunit.result.cache

test: install
	./vendor/bin/phpunit
	./vendor/bin/php-cs-fixer fix --dry-run -v
	./vendor/bin/phpmd  src/,test/ text ./phpmd.xml

coverage: install
	phpdbg -qrr ./vendor/bin/phpunit --coverage-clover dist/tests.clover
	./vendor/bin/php-coveralls -v --coverage_clover='./dist/tests.clover' --json_path='./dist/coveralls-upload.json'

update:
	composer update --no-interaction

format: install
	./vendor/bin/php-cs-fixer fix -v
