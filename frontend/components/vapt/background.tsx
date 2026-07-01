export function VaptBackground() {
  return (
    <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden" aria-hidden="true">
      {/* Animated gradient orbs */}
      <div
        className="vapt-orb vapt-orb-1"
        style={{
          top: "-10%",
          left: "5%",
          width: "520px",
          height: "520px",
          background: "rgba(59,130,246,0.08)",
        }}
      />
      <div
        className="vapt-orb vapt-orb-2"
        style={{
          top: "20%",
          right: "0%",
          width: "480px",
          height: "480px",
          background: "rgba(99,102,241,0.07)",
        }}
      />
      <div
        className="vapt-orb vapt-orb-3"
        style={{
          bottom: "-10%",
          left: "30%",
          width: "600px",
          height: "600px",
          background: "rgba(139,92,246,0.05)",
        }}
      />
    </div>
  )
}
