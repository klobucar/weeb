package main

import (
	"fmt"
	"image/color"
	"math"
	"strings"

	"charm.land/lipgloss/v2"
)

// hslHex converts an HSL color to a "#RRGGBB" string. h is in degrees, s and l
// in [0,1]. Used to synthesize smooth rainbows the 256-color palette can't.
func hslHex(h, s, l float64) string {
	h = math.Mod(math.Mod(h, 360)+360, 360)
	c := (1 - math.Abs(2*l-1)) * s
	x := c * (1 - math.Abs(math.Mod(h/60, 2)-1))
	m := l - c/2
	var r, g, b float64
	switch {
	case h < 60:
		r, g, b = c, x, 0
	case h < 120:
		r, g, b = x, c, 0
	case h < 180:
		r, g, b = 0, c, x
	case h < 240:
		r, g, b = 0, x, c
	case h < 300:
		r, g, b = x, 0, c
	default:
		r, g, b = c, 0, x
	}
	return fmt.Sprintf("#%02X%02X%02X", int((r+m)*255+0.5), int((g+m)*255+0.5), int((b+m)*255+0.5))
}

// rainbowText paints each (non-space) rune along a moving hue gradient. frame
// shifts the whole rainbow so callers can animate it; step is degrees of hue per
// character.
func rainbowText(s string, frame int) string {
	return rainbowStep(s, frame, 14, true)
}

func rainbowStep(s string, frame int, step float64, bold bool) string {
	var b strings.Builder
	base := float64(frame) * 8
	for i, r := range []rune(s) {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		st := lipgloss.NewStyle().Foreground(lipgloss.Color(hslHex(base+float64(i)*step, 0.95, 0.62)))
		if bold {
			st = st.Bold(true)
		}
		b.WriteString(st.Render(string(r)))
	}
	return b.String()
}

// rainbowHue returns a single animated color from the rainbow — handy for things
// like a cycling border where one color, not per-rune, is wanted.
func rainbowHue(frame int, offset float64) color.Color {
	return lipgloss.Color(hslHex(float64(frame)*10+offset, 0.9, 0.6))
}

// gradientText paints a static (non-animated) gradient across s, sweeping the
// hue from h0 to h1 degrees. This is the "always on" color flair — distinct from
// the animated rainbow mode — used for titles and dividers.
func gradientText(s string, h0, h1 float64, bold bool) string {
	runes := []rune(s)
	n := len(runes)
	if n == 0 {
		return s
	}
	var b strings.Builder
	for i, r := range runes {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		t := 0.0
		if n > 1 {
			t = float64(i) / float64(n-1)
		}
		h := h0 + (h1-h0)*t
		st := lipgloss.NewStyle().Foreground(lipgloss.Color(hslHex(h, 0.85, 0.65)))
		if bold {
			st = st.Bold(true)
		}
		b.WriteString(st.Render(string(r)))
	}
	return b.String()
}

// gradientHue returns the single color at position t∈[0,1] along the h0→h1 sweep.
func gradientHue(h0, h1, t float64) color.Color {
	return lipgloss.Color(hslHex(h0+(h1-h0)*t, 0.85, 0.6))
}
