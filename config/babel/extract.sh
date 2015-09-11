#!/usr/bin/env bash
# to create new translations, run something like
# pybabel init -i messages.pot -d ../../frontend/translations -l fr
# and change 'fr' to whatever you need.

pybabel extract -F babel.cfg -k ___ -k _ -o messages.pot ../../