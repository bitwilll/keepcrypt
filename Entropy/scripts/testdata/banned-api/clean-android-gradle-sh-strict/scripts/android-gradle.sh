"$dist/gradle-$version/bin/gradle" --no-daemon --no-scan --dependency-verification strict --project-dir "$project" "$@"
"$dist/gradle-$version/bin/gradle" --no-daemon -F strict "$@"
