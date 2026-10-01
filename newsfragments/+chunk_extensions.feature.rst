Added an optional chunk-extension preservation mode: pass
``preserve_chunk_extensions=True`` to :class:`~h11.Connection` to expose
chunked transfer-encoding chunk extensions as ``Data.chunk_extensions`` (and
``EndOfMessage.chunk_extensions`` for the final zero-length chunk), and to
re-encode them when sending. Extensions support token and quoted-string
values, repeated names, and empty values; values that would allow newline
injection are rejected.
