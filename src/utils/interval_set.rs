use std::ops::Range;

#[derive(Default, Clone)]
pub struct IntervalSet<T: PartialOrd + Copy>(Vec<Range<T>>);

enum Pos {
    Below(usize),
    Above(usize),
    Contains(usize),
}

enum Affected {
    Ranges(usize, usize),
    None(usize),
}

impl<T: PartialOrd + Copy> IntervalSet<T> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    fn find_pos(&self, value: T) -> Pos {
        if self.0.is_empty() {
            return Pos::Above(0);
        }
        let mut idx = self.0.len() / 2;
        let mut offset = (idx + 1) / 2;
        while offset != 0 {
            if self.0[idx].start > value {
                idx -= offset;
            } else if value < self.0[idx].end {
                return Pos::Contains(idx);
            } else {
                idx += offset;
            }
            offset /= 2;
        }
        if value < self.0[idx].start {
            Pos::Below(idx)
        } else if value < self.0[idx].end {
            Pos::Contains(idx)
        } else {
            Pos::Above(idx)
        }
    }

    pub fn contains(&self, value: T) -> bool {
        matches!(self.find_pos(value), Pos::Contains(_))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn min_inclusive(&self) -> Option<T> {
        self.0.first().map(|r| r.start)
    }

    pub fn max_exclusive(&self) -> Option<T> {
        self.0.last().map(|r| r.end)
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }

    fn affected(&self, interval: &Range<T>) -> Affected {
        let start_pos = self.find_pos(interval.start);
        let end_pos = self.find_pos(interval.end);
        match start_pos {
            Pos::Contains(start) => match end_pos {
                Pos::Contains(end) => Affected::Ranges(start, end),
                Pos::Below(end) => {
                    if end < self.0.len() {
                        if self.0[end].start < interval.end {
                            Affected::Ranges(start, end - 1)
                        } else {
                            Affected::Ranges(start, end)
                        }
                    } else {
                        Affected::Ranges(start, end - 1)
                    }
                }
                Pos::Above(end) => Affected::Ranges(start, end),
            },
            Pos::Below(start) => match end_pos {
                Pos::Contains(end) => {
                    if start == 0
                        || (start != self.0.len()
                            && interval
                                .end
                                .partial_cmp(&self.0[start].start)
                                .map(|ord| ord.is_ge())
                                .unwrap_or(true))
                    {
                        Affected::Ranges(start, end)
                    } else {
                        Affected::Ranges(start - 1, end)
                    }
                }
                Pos::Below(end) => {
                    if start == end {
                        Affected::None(start)
                    } else if interval.end < self.0[end].start {
                        Affected::Ranges(start, end - 1)
                    } else {
                        Affected::Ranges(start, end)
                    }
                }
                Pos::Above(end) => {
                    let start = if start == 0
                        || interval
                            .end
                            .partial_cmp(&self.0[start].start)
                            .map(|ord| ord.is_ge())
                            .unwrap_or(true)
                    {
                        start
                    } else {
                        start - 1
                    };
                    if end + 1 < self.0.len()
                        && interval
                            .end
                            .partial_cmp(&self.0[end + 1].start)
                            .map(|ord| ord.is_ge())
                            .unwrap_or(true)
                    {
                        Affected::Ranges(start, end + 1)
                    } else {
                        Affected::Ranges(start, end)
                    }
                }
            },
            Pos::Above(start) => match end_pos {
                Pos::Contains(end) => {
                    if interval.start > self.0[start].end {
                        Affected::Ranges(start + 1, end)
                    } else {
                        Affected::Ranges(start, end)
                    }
                }
                Pos::Below(end) => {
                    let start = if interval.start > self.0[start].end {
                        start + 1
                    } else {
                        start
                    };
                    if interval.end < self.0[end].start {
                        Affected::Ranges(start, end - 1)
                    } else {
                        Affected::Ranges(start, end)
                    }
                }
                Pos::Above(end) => {
                    if start == end {
                        Affected::None(start)
                    } else if interval.start > self.0[start].end {
                        Affected::Ranges(start + 1, end)
                    } else {
                        Affected::Ranges(start, end)
                    }
                }
            },
        }
    }

    pub fn insert(&mut self, interval: Range<T>) {
        let afct = self.affected(&interval);
        match afct {
            Affected::Ranges(start, end) => {
                if interval.start < self.0[start].start {
                    self.0[start].start = interval.start;
                }
                if self.0[end].end < interval.end {
                    self.0[start].end = interval.end;
                } else {
                    self.0[start].end = self.0[end].end;
                }
                if start != end {
                    let start = start + 1;
                    let end = end + 1;
                    let mut i = 0;
                    while start + i < end && end + i < self.0.len() {
                        self.0.swap(start + i, end + i);
                        i += 1;
                    }
                    self.0.truncate(start + i);
                }
            }
            Affected::None(idx) => {
                if idx == self.0.len() {
                    self.0.push(interval);
                } else {
                    self.0.insert(idx, interval);
                }
            }
        }
    }

    pub fn remove(&mut self, interval: Range<T>) {
        let afct = self.affected(&interval);
        if let Affected::Ranges(start, end) = afct {
            if start == end {
                if self.0[start].start < interval.start {
                    if interval.end < self.0[start].end {
                        if start + 1 < self.0.len() {
                            self.0.insert(start + 1, interval.end..self.0[start].end);
                        } else {
                            self.0.push(interval.end..self.0[start].end)
                        }
                        self.0[start].end = interval.start;
                    } else {
                        self.0[start].end = interval.start;
                    }
                } else if interval.end < self.0[start].end {
                    self.0[start].start = interval.end;
                } else {
                    self.0.remove(start);
                }
            } else if start + 1 == end {
                if self.0[start].start < interval.start {
                    self.0[start].end = interval.start;
                    if interval.end < self.0[end].end {
                        self.0[end].start = interval.end;
                    } else {
                        self.0.remove(end);
                    }
                } else {
                    if interval.end < self.0[end].end {
                        self.0[end].start = interval.end;
                    } else {
                        self.0.remove(end);
                    }
                    self.0.remove(start);
                }
            } else {
                let (start, end) = if self.0[start].start < interval.start {
                    if interval.end < self.0[end].end {
                        (start, end + 1)
                    } else {
                        self.0[end].start = interval.end;
                        (start, end)
                    }
                } else {
                    self.0[start].end = interval.start;
                    if interval.end < self.0[end].end {
                        (start + 1, end + 1)
                    } else {
                        self.0[end].start = interval.end;
                        (start + 1, end)
                    }
                };

                let mut i = 0;
                while start + i < end && end + i < self.0.len() {
                    self.0.swap(start + i, end + i);
                    i += 1;
                }
                self.0.truncate(start + i);
            }
        };
    }

    pub fn intervals(&self) -> &[Range<T>] {
        &self.0[..]
    }
}
