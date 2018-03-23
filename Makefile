.PHONY: install clean test coverage update format

install:
	composer install --no-interaction

clean:
	rm -rf vendor/ dist/

test: install
	./vendor/bin/phpunit
	./vendor/bin/php-cs-fixer fix --dry-run -v
	./vendor/bin/phpmd  src/,test/ text ./phpmd.xml
	./vendor/bin/phpcpd src/ test/
	./vendor/bin/phploc src/

coverage: install
	./vendor/bin/phpunit --coverage-clover=dist/tests.clover

update:
	composer update --no-interaction

format: install
	./vendor/bin/php-cs-fixer fix -v
