// This is your config file, place any global data here.
// You can import this data from anywhere in your site by using the `import` keyword.

type Config = {
  title: string;
  description: string;
  lang: string;
  profile: {
    author: string;
    description?: string;
  }
}

type SocialLink = {
  icon: string;
  friendlyName: string; // for accessibility
  link: string;
}

export const siteConfig: Config = {
  title: "jp's website",
  description: "",
  lang: "en-GB",
  profile: {
    author: "Jake Park",
    description: "Computer Science Student in Bergen County Technical High Schools Teterboro. "
  }
}

/** 
  These are you social media links. 
  It uses https://github.com/natemoo-re/astro-icon#readme
  You can find icons @ https://icones.js.org/
*/
export const socialLinks: Array<SocialLink> = [
  {
    icon: "mdi:github",
    friendlyName: "Github",
    link: "https://github.com/jp0x1",
  },
  {
    icon: "mdi:linkedin",
    friendlyName: "LinkedIn",
    link: "https://www.linkedin.com/in/jake-park-4222a9281/",
  },
  {
    icon: "mdi:email",
    friendlyName: "email",
    link: "mailto:jakepark2908@gmail.com",
  }
];

export const NAV_LINKS: Array<{ title: string, path: string }> = [
  {
    title: "Home",
    path: "/",
  },
  {
    title: "About",
    path: "/about",
  },
  {
    title: "Blogs",
    path: "/blog",
  },
  {
    title: "Projects",
    path: '/projects'
  }
];
