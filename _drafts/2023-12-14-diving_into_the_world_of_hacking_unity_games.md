---
title: Diving into the world of modding Unity games
date: 2023-12-14 12:00:00 +0900
categories: [Low level, game hacking]
tags: [csharp]
img_path: /assets/img/posts/diving_into_the_world_of_modding_unity_games/
image:
  path: header.png
  lqip: header.svg
  alt: header
---

## Introduction

Hi there, today I'm going to talk about how I tackled a Unity game, specifically compiled with Mono, for the first time to make ESP and surprised how it was easy to accomplish.

The content will be
- Include game's files to our project to access them
- Code of loader class and hack class
- Take a look at game assemblies using dnSpy
- How to inject our dll into Mono game

I've also read public articles about Unity hacking and tried some myself, but there are parts that I'm still not sure how they work. Apporogies

I recommend to see this post and [pseuxide/lethal_to_company](https://github.com/pseuxide/lethal_to_company) side by side so that you can catch up with code that i may not mention in the article.

### Introduction to Lethal Company

In this post, I'll take the game [Lethal Company](https://store.steampowered.com/app/1966720/Lethal_Company/) as an target. (I enjoyed it recently with my friends)

It's worth knowing a bit about the target game before reading this article, let me briefly introduce you to it. This sentences are quorted from its Steam page.

> You are a contracted worker for the Company. Your job is to collect scrap from abandoned, industrialized moons to meet the Company's profit quota. You can use the cash you earn to travel to new moons with higher risks and rewards--or you can buy fancy suits and decorations for your ship. Experience nature, scanning any creature you find to add them to your bestiary. Explore the wondrous outdoors and rummage through their derelict, steel and concrete underbellies. Just never miss the quota.

Basically it's a FPS game where you collect scraps in the planets that monsters are crawling around.

## Target reader

Those who
- me in the future
- can barely write C#

## main content

Why it's a cinch to develop a mod of Unity? Essentially, by using C# as a language you're allowed to use all resources the game uses in your mod code like classes, functions even member variables too.

It almost feels like you're using dynamic library of the game lol.

### Setting up Visual Studio project

Right off the bat, create a C# Class Library project. Remember we're making internal mod.

Then, right click **References** on the solution explorer and click **Add Reference** -> **Browse** and go to root directory of the Lethal Company and find folder called `Managed` which typically located in root/GAMENAME_Data folder.

In the folder, there should be bunch of .dlls yet the ones we're interested in is what's called `Assenbly-CSharp.dll`, `Assembly-CSharp-firstpass.dll` and all the files starts their name with `Unity` and `UnityEngine`.

By now we added all we need which allow us to use all the fun stuff inside the game. The magic word `using UnityEngine;` gives us the power from now on.

### dllmain

To perform work after get injected define what's equivalent to dllmain in C++ haha.

```cs
using UnityEngine;

namespace lethal_to_company
{
    public class loader
    {
        private static readonly GameObject MGameObject = new GameObject();

        public static void load()
        {
            MGameObject.AddComponent<hack>();
            Object.DontDestroyOnLoad(MGameObject);
        }
        public static void unload()
        {
            Object.Destroy(MGameObject);
        }
    }
}
```
{: file='loader.cs'}

It's making GameObject, and adding component which is the body of our hack.
Remember the namespace, class name and function name will be required when we inject the produced dll. In our case, `lethal_to_company`, `loader`, `load`.


### hack code body

Apparently OnGUI function is Unity's rendering function which runs at the end of the each frame and we override this function to render our esp.

```cs
public void OnGUI()
{
  foreach (var go in grabbable_objects)
  {
    esp(go.transform.position, Color.green);
  }
  foreach (var enemy in enemies)
  {
    esp(enemy.transform.position, Color.red);
  }
}

private EnemyAI[] enemies;
private PlayerControllerB local_player;
private GrabbableObject[] grabbable_objects;
private Camera camera;
```

I'll show you the esp function and how I update the entity real time later but let me show you about Lethal Company's in-game entities `GrabbableObject[]` and `EnemyAI[]` first. Let's fire up dnSpy and take a look at in-game objects statically.

### esp function

```cs
using UnityEngine;
using System;

namespace lethal_to_company
{
  partial class hack : MonoBehaviour
  {
    private Vector3 world_to_screen(Vector3 world)
    {
      Vector3 screen = camera.WorldToViewportPoint(world);

      screen.x *= Screen.width;
      screen.y *= Screen.height;

      screen.y = Screen.height - screen.y;

      return screen;
    }

    private float distance(Vector3 world_position)
    {
      return Vector3.Distance(camera.transform.position, world_position);
    }

    private void esp(Vector3 entity_position, Color color)
    {
      if (camera == null)
      {
        console.write_line("camera is null");
        return;
      }

      Vector3 entity_screen_pos = world_to_screen(entity_position);

      if (entity_screen_pos.z < 0 || Math.Abs(entity_position.y - local_player.transform.position.y) > 50)
      {
        return;
      }

      float distance_to_entity = distance(entity_position);
      float box_width = 300 / distance_to_entity;
      float box_height = 300 / distance_to_entity;

      float box_thickness = 3f;

      if (entity_screen_pos.x > 0 && entity_screen_pos.x < Screen.width && entity_screen_pos.y > 0 && entity_screen_pos.y < Screen.height)
      {
        render.draw_box_outline(
          new Vector2(entity_screen_pos.x - box_width / 2, entity_screen_pos.y - box_height / 2), box_width,
          box_height,
          color, box_thickness);
        render.draw_line(new Vector2(Screen.width / 2, Screen.height),
          new Vector2(entity_screen_pos.x, entity_screen_pos.y + box_height / 2), color, 2f);
      }
    }
  }
}
```

This is the esp function and some other utilities it uses.
In terms of world to screen mechanism, usually `camera.WorldToScreenPoint` which is predefined by Unity is used among game hackers, but somehow this game's WorldToScreenPoint function doesnt produce correct result. Frankly speaking I got stuck due to this a few days.

https://www.unknowncheats.me/forum/3921191-post32.html
