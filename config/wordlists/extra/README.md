# Optional extra wordlists

Drop one or more `.txt` files here to extend the bundled fuzzing lists. The
corpus is split by kind so it never lands in the wrong kind of scan:

```
config/wordlists/extra/common/discovery.txt   # host and path discovery
config/wordlists/extra/params/parameters.txt  # query-parameter discovery
```

Then run `trishul --update` to merge them into `common.txt` and `params.txt`.

TRISHUL never downloads wordlists and never uses a remote repository as a
data source. The files in this directory are yours to place and yours to
remove.

Only use corpora you are authorised to use against the target — a larger list
means more requests against the target.
