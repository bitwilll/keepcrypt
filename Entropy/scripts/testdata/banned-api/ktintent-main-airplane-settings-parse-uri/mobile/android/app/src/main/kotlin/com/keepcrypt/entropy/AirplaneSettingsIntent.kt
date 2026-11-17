// Only the airplane-mode settings intent passes here, written whole.
fun open(ctx: Context, link: String) = ctx.startActivity(Intent.parseUri(link, 0))
