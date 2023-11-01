SHELL := /bin/bash
VENV := python3 -m venv
ENVDIR := env3
ACTIVATE := $(ENVDIR)/bin/activate

.PHONY: test deps deps-dev clean deploy

clean:
	rm -r $(ENVDIR) || :

deps:
	[[ ! -f $(ACTIVATE) ]] && { \
		$(VENV) $(ENVDIR) && \
		sed -i 's/include-system-site-packages = false/include-system-site-packages = true/g' env3/pyvenv.cfg ; } || :
	. $(ACTIVATE) && pip3 install -r requirements.txt && pip3 install twine ; deactivate

deps-dev:
	[[ ! -f $(ACTIVATE) ]] && $(VENV) $(ENVDIR) || :
	. $(ACTIVATE) && pip3 install -r requirements-dev.txt ; deactivate

test: deps deps-dev
	. $(ACTIVATE) && nose2 -v ; deactivate

deploy: clean test
	. $(ACTIVATE) && twine upload dist/*
	#python setup.py sdist upload --show-response -v --repository=https://upload.pypi.org/legacy/
