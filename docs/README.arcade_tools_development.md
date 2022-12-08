ARCADE Development, notes for people working on these tools:

  - 'dev' branch is what all PR's shold be made against
  - rebase upstream 'dev' branch constantly as you work!

  - Base tooling must be scrutinized for quality,
    - anything in `./bin`
    - anything in `./lib`

  - User interface tooling can be created fast and loose,
    - anything in `./libexec`
    - any language is appropriate, if your utility exits 0 on success, nonzero on failure.
    - making a new command:
      - drop a program into `./libexec` which begins with `grv-<something>`
      - grv tooling will immediately work with that tool, e.g `grv something`

