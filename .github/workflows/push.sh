#!/usr/bin/env bash

set -euox pipefail

sha=$1
sha=${sha::8}
event=$2
pr=$3

case "$event" in
"push")
	tag=$QUAY_REPO:sha-$sha
	;;
"pull_request")
	QUAY_REPO+=-pr
	tag=$QUAY_REPO:pr$pr-sha-$sha
	;;
*)
	echo "unknown event_type:$event" >&2
	exit 1
	;;
esac

docker images --format '{{.Repository}} {{.Tag}} {{.ID}}' | sort | awk '/ci-image-build/ {printf "%s %s\n", $2, $3}' | while read -r oldtag id; do
	# shellcheck disable=SC2001
	t=$tag-$(sed 's|sha-[0-9a-z]\+-||' <<<"$oldtag")
	docker tag "$id" "$t"
	docker rmi "ci-image-build:$oldtag"
	docker push -q "$t"
done

mapfile -t digests < <(docker images --format '{{.Digest}}' --filter reference="$QUAY_REPO" | sort | sed "s|^|$QUAY_REPO@|" | tr '\n' ' ')
# shellcheck disable=SC2068
docker manifest create "$tag" ${digests[@]}
docker manifest push "$tag"

QUAY_REPO_URL=https://quay.io/api/v1/repository/${QUAY_REPO/"quay.io/"/}
set +x
docker images --format '{{.Tag}}' --filter reference="$tag-*" | sort | while read -r tag; do
	url=$QUAY_REPO_URL/tag/$tag
	echo "deleting $url"
	curl \
		--fail \
		--oauth2-bearer "$QUAY_API_TOKEN" \
		--retry 5 \
		--retry-connrefused \
		--retry-delay 2 \
		--silent \
		-XDELETE \
		"$url"
done
