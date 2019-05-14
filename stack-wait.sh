#!/bin/sh
limit=30;
until [ -z "$(docker service ls --filter label=com.docker.stack.namespace=dpx -q)" ] || [ "$limit" -lt 0 ]; do
	echo "waiting for services..."
	sleep 2;
	limit="$((limit-1))";
done

limit=30;
until [ -z "$(docker network ls --filter label=com.docker.stack.namespace=dpx -q)" ] || [ "$limit" -lt 0 ]; do
	echo "waiting for network..."
	sleep 2;
	limit="$((limit-1))";
done
