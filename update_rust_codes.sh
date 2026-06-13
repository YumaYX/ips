#!/bin/bash

find src -name "*.rs" | sort | xargs -I@ bash ./update_rust_code.sh @
