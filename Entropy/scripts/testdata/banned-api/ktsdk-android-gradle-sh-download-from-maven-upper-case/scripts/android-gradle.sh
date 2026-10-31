"$dist/gradle-$version/bin/gradle" --no-daemon --no-scan -Pkotlin.native.distribution.downloadFromMaven=FALSE --project-dir "$project" "$@"
