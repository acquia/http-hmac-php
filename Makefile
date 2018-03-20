.PHONY: install clean test coverage update

install:
	composer install --no-interaction

clean:
	rm -rf vendor/ dist/

test: install
	./vendor/bin/phpunit
	./vendor/bin/phpcs --standard=PSR2 --runtime-set ignore_warnings_on_exit 1 src/ test/
	./vendor/bin/phpmd  src/,test/ text ./phpmd.xml
	./vendor/bin/phpcpd src/ test/
	./vendor/bin/phploc src/

coverage: install
	./vendor/bin/phpunit --coverage-clover=dist/tests.clover

update:
	composer update --no-interaction
