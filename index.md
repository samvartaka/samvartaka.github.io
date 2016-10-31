---
layout: page
title: SAMVARTAKA
tagline: "When you want to know how things really work, study them when they're coming apart."
---
{% include JB/setup %}

## Posts

<ul class="posts">
  {% for post in site.posts %}
    <li><span>{{ post.date | date_to_string }}</span> &raquo; <a href="{{ BASE_PATH }}{{ post.url }}">{{ post.title }}</a></li>
  {% endfor %}
</ul>


