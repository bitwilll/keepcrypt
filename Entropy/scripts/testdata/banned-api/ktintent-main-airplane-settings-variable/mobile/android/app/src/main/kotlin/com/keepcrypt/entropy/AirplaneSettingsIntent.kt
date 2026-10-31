// Only the airplane-mode settings intent passes here, written whole.
fun open(ctx: Context, next: Intent) = ctx.startActivity(next)
