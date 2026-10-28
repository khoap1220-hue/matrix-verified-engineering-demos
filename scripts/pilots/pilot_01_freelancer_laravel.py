# -*- coding: utf-8 -*-
"""Pilot 01 (Freelancer FLP-40790593): Laravel Suburb & Area Auto-Page Creation Module."""
import re
from typing import Any


def slugify_suburb(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")


def generate_laravel_suburb_pages(
    main_pages: list[str], areas: list[str], suburbs: list[str], template_body: str
) -> list[dict[str, Any]]:
    """Sinh tự động 3 trang chính cho toàn bộ danh sách Suburb & Area chuẩn SEO Laravel."""
    generated: list[dict[str, Any]] = []
    for page in main_pages[:3]:
        for area in areas:
            for suburb in suburbs:
                slug = f"{slugify_suburb(page)}-{slugify_suburb(suburb)}-{slugify_suburb(area)}"
                title = f"{page.strip()} in {suburb.strip()}, {area.strip()} | Verified Local Service"
                meta_desc = (
                    f"Professional {page.strip().lower()} services in {suburb.strip()} ({area.strip()}). "
                    f"{template_body.strip()}"
                )[:160]
                generated.append(
                    {
                        "route_slug": f"/{slug}",
                        "seo_title": title,
                        "meta_description": meta_desc,
                        "suburb": suburb.strip(),
                        "area": area.strip(),
                        "page_type": page.strip(),
                        "status": "PUBLISHED",
                    }
                )
    return generated
