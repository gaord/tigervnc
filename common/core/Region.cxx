/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
 * Copyright 2016-2020 Pierre Ossman for Cendio AB
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <core/LogWriter.h>
#include <core/Region.h>

#ifndef OHOS
extern "C" {
#include <pixman.h>
}
#endif

using namespace core;

static LogWriter vlog("Region");

#ifdef OHOS
Region::Region()
  : hasRect(false), rect(0, 0, 0, 0)
{
}

Region::Region(const Rect& r)
  : hasRect(!r.is_empty()), rect(r)
{
  if (!hasRect)
    rect = Rect(0, 0, 0, 0);
}

Region::Region(const Region& r)
  : hasRect(r.hasRect), rect(r.rect)
{
}

Region::~Region()
{
}

Region& Region::operator=(const Region& r)
{
  hasRect = r.hasRect;
  rect = r.rect;
  return *this;
}

void Region::clear()
{
  hasRect = false;
  rect = Rect(0, 0, 0, 0);
}

void Region::reset(const Rect& r)
{
  hasRect = !r.is_empty();
  rect = hasRect ? r : Rect(0, 0, 0, 0);
}

void Region::translate(const Point& delta)
{
  if (!hasRect)
    return;
  rect = rect.translate(delta);
}

void Region::assign_intersect(const Region& r)
{
  if (!hasRect || !r.hasRect) {
    clear();
    return;
  }
  rect = rect.intersect(r.rect);
  hasRect = !rect.is_empty();
  if (!hasRect)
    rect = Rect(0, 0, 0, 0);
}

void Region::assign_union(const Region& r)
{
  if (!r.hasRect)
    return;
  if (!hasRect) {
    hasRect = true;
    rect = r.rect;
    return;
  }
  rect = rect.union_boundary(r.rect);
  hasRect = !rect.is_empty();
  if (!hasRect)
    rect = Rect(0, 0, 0, 0);
}

void Region::assign_subtract(const Region& r)
{
  if (!hasRect || !r.hasRect)
    return;
  if (rect.enclosed_by(r.rect))
    clear();
}

Region Region::intersect(const Region& r) const
{
  Region ret(*this);
  ret.assign_intersect(r);
  return ret;
}

Region Region::union_(const Region& r) const
{
  Region ret(*this);
  ret.assign_union(r);
  return ret;
}

Region Region::subtract(const Region& r) const
{
  Region ret(*this);
  ret.assign_subtract(r);
  return ret;
}

bool Region::operator==(const Region& r) const
{
  if (!hasRect && !r.hasRect)
    return true;
  if (hasRect != r.hasRect)
    return false;
  return rect == r.rect;
}

bool Region::operator!=(const Region& r) const
{
  return !(*this == r);
}

int Region::numRects() const
{
  return hasRect ? 1 : 0;
}

bool Region::get_rects(std::vector<Rect>* rects,
                       bool /*left2right*/, bool /*topdown*/) const
{
  rects->clear();
  if (!hasRect)
    return false;
  rects->push_back(rect);
  return true;
}

Rect Region::get_bounding_rect() const
{
  return hasRect ? rect : Rect(0, 0, 0, 0);
}

void Region::debug_print(const char* prefix) const
{
  Rect extents = get_bounding_rect();
  std::vector<Rect> rects;

  get_rects(&rects);

  vlog.debug("%s num rects %3ld extents %3d,%3d %3dx%3d",
             prefix, (long)rects.size(), extents.tl.x, extents.tl.y,
             extents.width(), extents.height());
}
#else
Region::Region()
{
  rgn = new struct pixman_region16;
  pixman_region_init(rgn);
}

Region::Region(const Rect& r)
{
  rgn = new struct pixman_region16;
  pixman_region_init_rect(rgn, r.tl.x, r.tl.y, r.width(), r.height());
}

Region::Region(const Region& r)
{
  rgn = new struct pixman_region16;
  pixman_region_init(rgn);
  pixman_region_copy(rgn, r.rgn);
}

Region::~Region()
{
  pixman_region_fini(rgn);
  delete rgn;
}

Region& Region::operator=(const Region& r)
{
  pixman_region_copy(rgn, r.rgn);
  return *this;
}

void Region::clear()
{
  // pixman_region_clear() isn't available on some older systems
  pixman_region_fini(rgn);
  pixman_region_init(rgn);
}

void Region::reset(const Rect& r)
{
  pixman_region_fini(rgn);
  pixman_region_init_rect(rgn, r.tl.x, r.tl.y, r.width(), r.height());
}

void Region::translate(const Point& delta)
{
  pixman_region_translate(rgn, delta.x, delta.y);
}

void Region::assign_intersect(const Region& r)
{
  pixman_region_intersect(rgn, rgn, r.rgn);
}

void Region::assign_union(const Region& r)
{
  pixman_region_union(rgn, rgn, r.rgn);
}

void Region::assign_subtract(const Region& r)
{
  pixman_region_subtract(rgn, rgn, r.rgn);
}

Region Region::intersect(const Region& r) const
{
  Region ret;
  pixman_region_intersect(ret.rgn, rgn, r.rgn);
  return ret;
}

Region Region::union_(const Region& r) const
{
  Region ret;
  pixman_region_union(ret.rgn, rgn, r.rgn);
  return ret;
}

Region Region::subtract(const Region& r) const
{
  Region ret;
  pixman_region_subtract(ret.rgn, rgn, r.rgn);
  return ret;
}

bool Region::operator==(const Region& r) const
{
  return pixman_region_equal(rgn, r.rgn);
}

bool Region::operator!=(const Region& r) const
{
  return !pixman_region_equal(rgn, r.rgn);
}

int Region::numRects() const
{
  return pixman_region_n_rects(rgn);
}

bool Region::get_rects(std::vector<Rect>* rects,
                       bool left2right, bool topdown) const
{
  int nRects;
  const pixman_box16_t* boxes;
  int xInc, yInc, i;

  boxes = pixman_region_rectangles(rgn, &nRects);

  rects->clear();
  rects->reserve(nRects);

  xInc = left2right ? 1 : -1;
  yInc = topdown ? 1 : -1;
  i = topdown ? 0 : nRects-1;

  while (nRects > 0) {
    int firstInNextBand = i;
    int nRectsInBand = 0;

    while (nRects > 0 && boxes[firstInNextBand].y1 == boxes[i].y1)
    {
      firstInNextBand += yInc;
      nRects--;
      nRectsInBand++;
    }

    if (xInc != yInc)
      i = firstInNextBand - yInc;

    while (nRectsInBand > 0) {
      Rect r(boxes[i].x1, boxes[i].y1, boxes[i].x2, boxes[i].y2);
      rects->push_back(r);
      i += xInc;
      nRectsInBand--;
    }

    i = firstInNextBand;
  }

  return !rects->empty();
}

Rect Region::get_bounding_rect() const
{
  const pixman_box16_t* extents;
  extents = pixman_region_extents(rgn);
  return Rect(extents->x1, extents->y1, extents->x2, extents->y2);
}


void Region::debug_print(const char* prefix) const
{
  Rect extents;
  std::vector<Rect> rects;
  std::vector<Rect>::const_iterator iter;

  extents = get_bounding_rect();
  get_rects(&rects);

  vlog.debug("%s num rects %3ld extents %3d,%3d %3dx%3d",
          prefix, (long)rects.size(), extents.tl.x, extents.tl.y,
          extents.width(), extents.height());

  for (iter = rects.begin(); iter != rects.end(); ++iter) {
    vlog.debug("    rect %3d,%3d %3dx%3d",
               iter->tl.x, iter->tl.y, iter->width(), iter->height());
  }
}
#endif
