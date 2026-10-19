<!-- source: https://github.com/awslabs/mcp/discussions/2482
     fetched_from: https://github.com/awslabs/mcp/discussions/2482
     retrieved: 2026-10-19
     raw_sha256: 46df9898400c51bc668a69abd47ed849a6e9a5722f03b75f57b933be9e0f6733
     note: text extraction of the original page; formatting simplified -->

Not possible to set IAM --readonly when loading via the Core MCP server? · awslabs/mcp · Discussion #2482 · GitHub

 Skip to content

  You signed in with another tab or window. Reload to refresh your session. You signed out in another tab or window. Reload to refresh your session. You switched accounts on another tab or window. Reload to refresh your session. Dismiss alert

{{ message }}

#   Not possible to set IAM --readonly when loading via the Core MCP server?  #2482

 Unanswered
   anentropic   asked this question in Q&A

  Not possible to set IAM --readonly when loading via the Core MCP server?  #2482

    anentropic

 Feb 20, 2026 · 1 comment

 Return to top

   Discussion options

-

###  Uh oh!

There was an error while loading. Please reload this page.

#  {{title}}

 Something went wrong.

###  Uh oh!

There was an error while loading. Please reload this page.

##

 anentropic
  Feb 20, 2026

https://awslabs.github.io/mcp/servers/iam-mcp-server#read-only-mode <https://awslabs.github.io/mcp/servers/iam-mcp-server#read-only-mode>

Docs say:

Add the `--readonly` flag when starting the server:

```
# Using uvx
uvx awslabs.iam-mcp-server@latest --readonly

# Or if installed locally
python -m awslabs.iam_mcp_server.server --readonly
```

And:

#### Other MCP Clients

Simply add `"--readonly"` to the args array in your MCP configuration.

But what if I am just using https://awslabs.github.io/mcp/servers/core-mcp-server <https://awslabs.github.io/mcp/servers/core-mcp-server> with `"security-identity": true` ?

AFAICT there is no way to pass through that config

https://github.com/awslabs/mcp/blob/main/src/iam-mcp-server/awslabs/iam_mcp_server/server.py#L1576-L1589 <https://github.com/awslabs/mcp/blob/main/src/iam-mcp-server/awslabs/iam_mcp_server/server.py#L1576-L1589>

https://github.com/awslabs/mcp/blob/main/src/core-mcp-server/awslabs/core_mcp_server/server.py#L441-L451 <https://github.com/awslabs/mcp/blob/main/src/core-mcp-server/awslabs/core_mcp_server/server.py#L441-L451>

Maybe it'd be useful if args like `--read-only` all had an associated env var, e.g. `IAM_MCP_SERVER_READ_ONLY`, so that arbitrary sub-server config can be passed through from the Core mcp.json ?

  You must be logged in to vote

    All reactions

##  Replies:   1 comment

   Comment options

-

###  Uh oh!

There was an error while loading. Please reload this page.

#  {{title}}

 Something went wrong.

###  Uh oh!

There was an error while loading. Please reload this page.

###

 hippi345
  Oct 17, 2026

Good news: this got flipped around since you asked. The IAM server is now read-only by default. In `main()` the only flags are `--allow-write` and `--no-confirmation`, and if you don't pass `--allow-write` it starts with "Server started in READ-ONLY mode - all mutating operations are disabled" (server.py <https://github.com/awslabs/mcp/blob/main/src/iam-mcp-server/awslabs/iam_mcp_server/server.py>).

So if the IAM server is started with no extra args, which is what happens when Core loads it, you already get read-only. Mutating tools return an error unless someone adds `--allow-write`.

Heads up: the README's "Read-Only Mode" section still says to add `--readonly`, which is out of date now. If you run IAM on its own, it's just:

```
"args": ["awslabs.iam-mcp-server@latest"]                   // read-only
"args": ["awslabs.iam-mcp-server@latest", "--allow-write"]  // writes enabled
```

Also, `core-mcp-server` doesn't seem to be under `src/` on main anymore, so it's probably worth adding the IAM server directly to your mcp.json anyway.

  You must be logged in to vote

    All reactions

  0 replies

 Sign up for free to join this conversation on GitHub. Already have an account? Sign in to comment

 Category

 🙏
 Q&A

 Labels

 None yet

 2 participants

Heading

Bold

Italic

Quote

Code

Link

Numbered list

Unordered list

Task list

Attach files

Mention

Reference

   Menu

-

-

-

-

-

-

-

-

-

-

-

-

-

-

#  Select a reply

    Loading

###  Uh oh!

There was an error while loading. Please reload this page.

      Create a new saved reply
      reacted with thumbs up emoji     reacted with thumbs down emoji     reacted with laugh emoji     reacted with hooray emoji     reacted with confused emoji     reacted with heart emoji     reacted with rocket emoji     reacted with eyes emoji

   You can’t perform that action at this time.