use gpui::prelude::*;
use gpui::{
    App, Bounds, Div, Hsla, IntoElement, PathBuilder, Pixels, Point, RenderOnce, SharedString,
    StyleRefinement, Window, canvas, div, linear_color_stop, linear_gradient, point, px,
};
use i18n::t;

use crate::theme::ActiveTheme as _;

const GAP: f32 = 3.;
const OPACITY: f32 = 0.32;
const FLOOR: f32 = 0.03;
const STROKE: f32 = 2.;
const CHANNELS: [f32; 2] = [0.62, 1.];
const GLOW: f32 = 10.;
const GLOW_STROKE: f32 = 2.4;
const GLOW_OPACITY: f32 = 0.9;
/// A share of the band's own height, not of the box: a fixed share of the box leaves the line
/// floating over stubby bars on a quiet track.
const BEDDED: f32 = 0.55;
const RIDE: f32 = 0.4;
const FILL: f32 = 0.22;
const FILL_BASE: f32 = 0.05;
const LINE_BLUR: f32 = 0.7;
const CONTRAST: f32 = 0.34;

/// How the spectrum is drawn behind the fullscreen artwork.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VisualizerStyle {
    None,
    Bars,
    Wave,
    #[default]
    Both,
}

impl VisualizerStyle {
    pub const ALL: [Self; 4] = [Self::None, Self::Bars, Self::Wave, Self::Both];

    pub fn shown(self) -> bool {
        self != Self::None
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bars => "bars",
            Self::Wave => "wave",
            Self::Both => "both",
        }
    }

    pub fn from_id(id: &str) -> Self {
        match id {
            "none" => Self::None,
            "bars" => Self::Bars,
            "wave" => Self::Wave,
            _ => Self::default(),
        }
    }

    /// The localized name. Resolved at render, never stored.
    pub fn label(self) -> SharedString {
        match self {
            Self::None => t!("settings-visualizer-style-none"),
            Self::Bars => t!("settings-visualizer-style-bars"),
            Self::Wave => t!("settings-visualizer-style-wave"),
            Self::Both => t!("settings-visualizer-style-both"),
        }
    }

    fn bars(self) -> bool {
        matches!(self, Self::Bars | Self::Both)
    }

    fn wave(self) -> bool {
        matches!(self, Self::Wave | Self::Both)
    }
}

/// A frame of the spectrum as the visualizer draws it: one band set per channel.
#[derive(Clone, Debug, Default)]
pub struct Levels {
    pub left: Vec<f32>,
    pub right: Vec<f32>,
}

impl Levels {
    /// Both channels folded together, the louder of the two per band. What the bars draw.
    pub fn mixed(&self) -> Vec<f32> {
        let mut bands = self.left.clone();
        bands.resize(bands.len().max(self.right.len()), 0.);
        for (band, right) in bands.iter_mut().zip(&self.right) {
            *band = band.max(*right);
        }
        bands
    }
}

#[derive(IntoElement)]
pub struct Visualizer {
    base: Div,
    levels: Levels,
    max: Pixels,
    style: VisualizerStyle,
    tint: Option<Hsla>,
    behind: Option<Hsla>,
}

impl Visualizer {
    #[track_caller]
    pub fn new(levels: Levels, max: Pixels) -> Self {
        Self {
            base: div(),
            levels,
            max,
            style: VisualizerStyle::default(),
            tint: None,
            behind: None,
        }
    }

    pub fn style_kind(mut self, style: VisualizerStyle) -> Self {
        self.style = style;
        self
    }

    /// Defaults to the theme's primary; a caller that knows what is actually behind the
    /// visualizer — a cover-derived backdrop, say — passes its own.
    pub fn tint(mut self, tint: Hsla) -> Self {
        self.tint = Some(tint);
        self
    }

    pub fn behind(mut self, behind: Hsla) -> Self {
        self.behind = Some(behind);
        self
    }
}

impl Styled for Visualizer {
    fn style(&mut self) -> &mut StyleRefinement {
        self.base.style()
    }
}

impl RenderOnce for Visualizer {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let Self {
            mut base,
            levels,
            max,
            style,
            tint,
            behind,
        } = self;
        let theme = *cx.theme();
        let overrides = std::mem::take(base.style());
        let color = legible(
            tint.unwrap_or(theme.primary),
            behind.unwrap_or(theme.background),
        );

        let ride = match style {
            VisualizerStyle::Both => RIDE,
            _ => 0.,
        };
        let bar_color = match style {
            VisualizerStyle::Both => color.opacity(OPACITY * BEDDED),
            _ => color.opacity(OPACITY),
        };

        let mut visualizer = base
            .h(max)
            .relative()
            .when(style.bars(), |this| {
                this.child(bars(&levels, max, bar_color, ride))
            })
            .when(style.wave(), |this| {
                this.child(glow(levels.clone(), color))
                    .child(line(levels, color))
            });

        visualizer.style().refine(&overrides);
        visualizer
    }
}

fn bars(levels: &Levels, max: Pixels, color: Hsla, ride: f32) -> Div {
    div()
        .absolute()
        .inset_0()
        .flex()
        .items_end()
        .justify_center()
        .gap(px(GAP))
        .children(
            levels
                .mixed()
                .into_iter()
                .enumerate()
                .map(|(index, level)| {
                    div()
                        .id(("visualizer-bar", index))
                        .flex_1()
                        .bg(color)
                        .h(max * level.clamp(FLOOR, 1.) / (1. + ride))
                }),
        )
}

fn glow(levels: Levels, color: Hsla) -> Div {
    div().absolute().inset_0().blur(px(GLOW)).child(
        canvas(
            |_, _, _| {},
            move |bounds, _, window, _| wave(bounds, &levels, color, true, window),
        )
        .size_full(),
    )
}

fn line(levels: Levels, color: Hsla) -> impl IntoElement {
    canvas(
        |_, _, _| {},
        move |bounds, _, window, _| wave(bounds, &levels, color, false, window),
    )
    .absolute()
    .inset_0()
    .blur(px(LINE_BLUR))
}

fn wave(bounds: Bounds<Pixels>, levels: &Levels, color: Hsla, blurred: bool, window: &mut Window) {
    let channels = [&levels.left, &levels.right];
    if channels.iter().any(|bands| bands.len() < 2) || bounds.size.width <= px(0.) {
        return;
    }
    let width = match blurred {
        true => STROKE * GLOW_STROKE,
        false => STROKE,
    };
    let inset = px(width / 2.);
    let floor = bounds.origin.y + bounds.size.height;
    let span = (bounds.size.height - inset * 2.).max(px(0.));

    for (bands, weight) in channels.into_iter().zip(CHANNELS) {
        // A band owns a column, not a fence post: its point goes at the middle of the bar the
        // same band draws.
        let step = bounds.size.width / bands.len() as f32;
        let crest = |band: f32| floor - inset - span * band.clamp(FLOOR, 1.);
        let mut points = Vec::with_capacity(bands.len() + 2);
        points.push(point(bounds.origin.x, crest(bands[0])));
        points.extend(bands.iter().enumerate().map(|(index, band)| {
            point(bounds.origin.x + step * (index as f32 + 0.5), crest(*band))
        }));
        points.push(point(
            bounds.origin.x + bounds.size.width,
            crest(bands[bands.len() - 1]),
        ));

        let weight = match blurred {
            true => weight * GLOW_OPACITY,
            false => weight,
        };
        if !blurred {
            fill(&points, floor, color, weight, window);
        }
        stroke(
            &points,
            px(width),
            color.opacity(OPACITY * 2. * weight),
            window,
        );
    }
}

fn trace(builder: &mut PathBuilder, points: &[Point<Pixels>]) {
    builder.move_to(points[0]);
    // A Catmull-Rom spline as cubics. Unlike a quadratic through the midpoints it passes
    // through every point, so a crest lands on its band rather than shy of it.
    for index in 0..points.len() - 1 {
        let before = points[index.saturating_sub(1)];
        let from = points[index];
        let to = points[index + 1];
        let after = points[(index + 2).min(points.len() - 1)];
        builder.cubic_bezier_to(
            to,
            point(
                from.x + (to.x - before.x) / 6.,
                from.y + (to.y - before.y) / 6.,
            ),
            point(
                to.x - (after.x - from.x) / 6.,
                to.y - (after.y - from.y) / 6.,
            ),
        );
    }
}

fn stroke(points: &[Point<Pixels>], width: Pixels, color: Hsla, window: &mut Window) {
    let mut builder = PathBuilder::stroke(width);
    trace(&mut builder, points);
    match builder.build() {
        Ok(path) => window.paint_path(path, color),
        Err(error) => log::warn!("visualizer: cannot build the wave: {error}"),
    }
}

fn fill(points: &[Point<Pixels>], bottom: Pixels, color: Hsla, weight: f32, window: &mut Window) {
    let (Some(first), Some(last)) = (points.first(), points.last()) else {
        return;
    };
    let mut builder = PathBuilder::fill();
    trace(&mut builder, points);
    builder.line_to(point(last.x, bottom));
    builder.line_to(point(first.x, bottom));
    builder.close();
    match builder.build() {
        Ok(path) => window.paint_path(
            path,
            linear_gradient(
                180.,
                linear_color_stop(color.opacity(FILL * weight), 0.),
                linear_color_stop(color.opacity(FILL * FILL_BASE * weight), 1.),
            ),
        ),
        Err(error) => log::warn!("visualizer: cannot build the wave body: {error}"),
    }
}

/// Keeps `tint` readable on `behind` by pushing its lightness away from the surface's.
fn legible(tint: Hsla, behind: Hsla) -> Hsla {
    let distance = (tint.l - behind.l).abs();
    if distance >= CONTRAST {
        return tint;
    }
    let lighter = behind.l + CONTRAST;
    let darker = behind.l - CONTRAST;
    let l = match lighter <= 1. {
        true => lighter,
        false => darker.max(0.),
    };
    Hsla { l, ..tint }
}
