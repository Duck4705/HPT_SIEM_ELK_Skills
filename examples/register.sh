#!/bin/sh
set -eu

hpt-siem register --id demo --context analyst --url 'https://kibana.example.org/observability/s/security/app/home'
