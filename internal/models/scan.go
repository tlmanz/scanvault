// Package models is a compatibility shim. The canonical type is in
// github.com/tlmanz/scanvault/models. This file re-exports it so any
// internal code that still references this path compiles without change.
package models

import public "github.com/tlmanz/scanvault/models"

// Scan is an alias of the public Scan type.
type Scan = public.Scan

// SeverityCount is an alias of the public SeverityCount type.
type SeverityCount = public.SeverityCount

// VulnerabilitySummary is an alias of the public VulnerabilitySummary type.
type VulnerabilitySummary = public.VulnerabilitySummary

// VulnerabilityTrendPoint is an alias of the public VulnerabilityTrendPoint type.
type VulnerabilityTrendPoint = public.VulnerabilityTrendPoint
