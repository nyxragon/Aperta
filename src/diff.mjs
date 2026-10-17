// Stage 2b, the privilege diff.
// Subtract what a low-priv session actually exercised from the reconstructed model to
// positively enumerate the hidden, role-gated surface. This is the unit no shipped tool has:
// discovery tools dump the whole model (no diff); authz tools only see what you clicked.
export function diff(model, exercised, routeStatus) {
  const hiddenEndpoints = model.endpoints.filter(
    (e) => !exercised.has(`${e.method} ${e.path}`)
  );
  const hiddenRoutes = model.routes.filter((r) => routeStatus[r.path] === "blocked");
  return {
    hiddenRoutes,
    hiddenEndpoints,
    exercised: [...exercised].sort(),
  };
}
