#!/bin/bash

random() {
    bytes=$(dd if=/dev/random count=1 2>/dev/null | grep -ao "\w" | tr -d '\n' | cut -c1-15)

    echo -n $bytes
}

echo "userpin=$(random)
sopin=$(random)" > config/manager/.env.secret