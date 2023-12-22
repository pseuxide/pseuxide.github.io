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

I recommend to see this post and [pseuxide/lethal_to_company](https://github.com/pseuxide/lethal_to_company) side by side so that you can catch up with code that I may not mention in the article.

### Introduction to Lethal Company

In this post, I'll take the game [Lethal Company](https://store.steampowered.com/app/1966720/Lethal_Company/) as an target. (I enjoyed it recently with my friends)

It's worth knowing a bit about the target game before reading this article, let me briefly introduce you to it.

This sentences are quorted from its Steam page.

> You are a contracted worker for the Company. Your job is to collect scrap from abandoned, industrialized moons to meet the Company's profit quota. You can use the cash you earn to travel to new moons with higher risks and rewards--or you can buy fancy suits and decorations for your ship. Experience nature, scanning any creature you find to add them to your bestiary. Explore the wondrous outdoors and rummage through their derelict, steel and concrete underbellies. Just never miss the quota.

Basically it's a FPS game where you collect scraps in the planets that monsters are crawling around and sell them to your boss.

## Target reader

Those who
- me in the future
- can understand nature of C#

## main content

Why it's a cinch to develop a mod of Unity? Essentially, by using C# as a language you're allowed to use all resources the game uses in your mod code like classes, functions even member variables too.

It almost feels like you're using dynamic library of the game lol.

### Setting up Visual Studio project

Right off the bat, create a C# Class Library project. Remember we're making internal mod.

Then, right click **References** on the solution explorer and click **Add Reference** -> **Browse** and go to root directory of the Lethal Company and find folder called `Managed` which typically located in root/GAMENAME_Data folder.
![references](https://github.com/pseuxide/lethal_to_company/assets/33578715/2e407405-6208-41df-8cad-55e8c70c4d7b){: w="700" .normal}

In the folder, there should be bunch of .dlls yet the ones we're interested in is what's called `Assenbly-CSharp.dll`, `Assembly-CSharp-firstpass.dll` and all the files starts their name with `Unity` and `UnityEngine`. I know it's tremendous amount, but add them all anyway.

By now we added all we need which allow us to use all the fun stuff inside the game. The magic word `using UnityEngine;` gives us the power from now on.

### dllmain

To perform its functionality after injection, define what's equivalent to dllmain in C++.

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

Hit **Edit -> Search Assembly** to search text from entire Unity assemblies of the game (I believe it technically means every managed dlls in same folder).
When I look up enemy one class stands out, `EnemyAI` which sounds great. Click it and look at overview.
![enemy search result](https://github.com/pseuxide/lethal_to_company/assets/33578715/7163b0b1-88e9-4e39-8035-cfff6ca0a54d)

Indeed, the convincing symbol names are found in the class such as `SetEnemyStunned` or `this.isEnemyDead`.

![enemy class](https://github.com/pseuxide/lethal_to_company/assets/33578715/2a8ce698-2c90-4e16-ae4e-223f6936d56e){: w="700" .normal}

Ok now let's search for local player. When you seach `LocalPlayer`, 2 pure localplayer text come up which seems both of them are member variable of manager class. So basically you can obtain local player by `HUDManager.localPlayer` or `SoundManager.localPlayer`.

![local player](https://github.com/pseuxide/lethal_to_company/assets/33578715/46c47bff-c691-46f9-8972-d8f5319a6720)

Although they say `Camera.main` in your script let you get usable camera object, this game doesn't act like so. Neither `Camera.main` nor `Camera.current` work but instead local player has camera attached called gameplayCamera which sounds promissing.

After some test I found this camera is a real camera used in the game so I went with this.

![gameplay camera](https://github.com/pseuxide/lethal_to_company/assets/33578715/dfc9f119-3cbb-435b-a36c-a9f24074c3b4)

### How I update the entity

In the last section we've found entities we need (except grabbable object but it's similar anyways).
Now we have to update entity's info within a each few frame.

The main method is introduced by [this Guided Hacking post](https://guidedhacking.com/threads/how-to-hack-unity-mono-injection-codestage-anticheat.17915/). Apparently it's not performant way but frankly speaking I dont care now.

Let's be lazy and take the easiest way, the function `FindObjectsOfType` automatically look up every instances of the given type at runtime.
But, in case of local player, we get by `HUDManager.Instance.localPlayer`.

```cs
using UnityEngine;

namespace lethal_to_company
{
  partial class hack : MonoBehaviour
  {
    // Setup a timer and a set time to reset to
    private readonly float entity_update_interval = 5f;
    private float entity_update_timer;

    private void EntityUpdate()
    {
      if (entity_update_timer <= 0f)
      {
        enemies = FindObjectsOfType<EnemyAI>();
        grabbable_objects = FindObjectsOfType<GrabbableObject>();

        // You have to open menu to get local player lol
        local_player = HUDManager.Instance.localPlayer;

        assign_camera();

        clear_update_timer();
      }

      entity_update_timer -= Time.deltaTime;
    }

    private void clear_update_timer()
    {
      entity_update_timer = entity_update_interval;
    }
    private void assign_camera()
    {
      camera = local_player.gameplayCamera;
    }
  }
}
```

### esp function

This is the esp function and some other utilities it uses.

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

The only interesting thing here is about `world_to_screen` func. In terms of world to screen mechanism, people typically use `camera.WorldToScreenPoint` which is predefined by Unity, but somewhat this game's WorldToScreenPoint function produces a bit off result from expecting coordinates. Frankly speaking I got stuck a few days due to this.

Fortunately, I found [this post](https://www.unknowncheats.me/forum/3921191-post32.html) on UC forum saying 'use `camera.WorldToScreenViewportPoint` instead'. `WorldToScreenViewportPoint` is similar to `WorldToScreenPoint`, but it produces normalized coordinates on the screen. Official document says

> The bottom-left of the camera is (0,0); the top-right is (1,1). The z position is in world units from the camera.

Note that z axis refers to the depth from the camera. If z axis is positive value it means the object is in front of you and while not it's behind you.

Anyways, in case of this case `WorldToScreenViewportPoint` works as expected as opposed to `WorldToScreenPoint`, so multiply screen width and height to fit your resolution and BOOM it's done.


## Conclusion

![footer](footer.png)

Honestly, I'm not gonna get along with C# any further. However I've been wanting to scratch the surface of Mono modding once in my life. Indeed it was absolutely fresh experience from what I've been done with C++ and fun to manipulate game as if I modify game's source code directly.