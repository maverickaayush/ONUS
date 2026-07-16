/**
 * Hosting notice - plain fine print, matching the domain hint above (same muted
 * color/size, no box/border/icon). Two plain links, both to the repo.
 * Deliberately no scan number, ever.
 *
 * Single source of truth: rendered identically on the Scans (New Scan), Sign In,
 * and Sign Up pages. Edit the wording here only.
 */
export function HostingNotice() {
  return (
    <p className="mt-3.5 text-[11px] leading-relaxed text-ink-faint">
      This tool is{' '}
      <a
        href="https://github.com/maverickaayush/ONUS"
        target="_blank"
        rel="noopener noreferrer"
        className="text-accent hover:underline"
      >
        open source
      </a>{' '}
      - github.com/maverickaayush/ONUS. Hosted scans are limited to keep this free to use. For
      unlimited use,{' '}
      <a
        href="https://github.com/maverickaayush/ONUS"
        target="_blank"
        rel="noopener noreferrer"
        className="text-accent hover:underline"
      >
        support the repo
      </a>{' '}
      or run it locally.
    </p>
  )
}
