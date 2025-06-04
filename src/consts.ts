import type { IconMap, SocialLink, Site } from '@/types'

export const SITE: Site = {
  title: 'jake',
  description:
    'jake blog.',
  href: 'https://astro-erudite.vercel.app',
  author: 'jake',
  locale: 'en-US',
  featuredPostCount: 2,
  postsPerPage: 3,
}

export const NAV_LINKS: SocialLink[] = [
  {
    href: '/blog',
    label: 'blog',
  },
]

export const SOCIAL_LINKS: SocialLink[] = [
  {
    href: 'https://github.com/jp0x1',
    label: 'GitHub',
  },
 
  {
    href: 'mailto:jakepark2908@gmail.com',
    label: 'Email',
  },
  {
    href: '/rss.xml',
    label: 'RSS',
  },
]

export const ICON_MAP: IconMap = {
  Website: 'lucide:globe',
  GitHub: 'lucide:github',
  LinkedIn: 'lucide:linkedin',
  Twitter: 'lucide:twitter',
  Email: 'lucide:mail',
  RSS: 'lucide:rss',
}
