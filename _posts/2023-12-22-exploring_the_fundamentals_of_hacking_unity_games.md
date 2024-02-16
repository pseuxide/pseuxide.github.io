---
title: Exploring the fundamentals of hacking Unity games
date: 2023-12-22 12:00:00 +0900
categories: [low level]
tags: [csharp]
img_path: /assets/img/posts/exploring_the_fundamentals_of_hacking_unity_games/
image:
  path: header.png
  lqip: /assets/img/posts/exploring_the_fundamentals_of_hacking_unity_games/header.svg
  alt:
---

## Introduction

In this post I'll be talking about how I tackled a Unity game, specifically compiled with Mono, for the first time to make wall hack and surprised how it was easy to accomplish in comparison to the motherfucker, Unreal Engine.

The contents go on in such order

- Include game's files to our project to gain access to them
- Implementing loader class
- Implementing hack class
- Take a look at game assemblies using dnSpy
- How I update the game entities in real time
- Wall hack a.k.a ESP code
- How to inject our dll into Mono game

I've also read public articles about Unity hacking and tried some myself, but there are parts that I'm still not sure how they work. Apporogies

I recommend to see this post and [pseuxide/lethal_to_company](https://github.com/pseuxide/lethal_to_company) side by side so that you can catch up with code that I may not mention in the article.

## Introduction to Lethal Company

In this post, I'll take the game [Lethal Company](https://store.steampowered.com/app/1966720/Lethal_Company/) as an target (I enjoyed it recently with my friends).
And it's worth knowing a bit about the target game before reading this article, let me briefly introduce you to it.

This sentences are quorted from its Steam page.

> You are a contracted worker for the Company. Your job is to collect scrap from abandoned, industrialized moons to meet the Company's profit quota. You can use the cash you earn to travel to new moons with higher risks and rewards--or you can buy fancy suits and decorations for your ship. Experience nature, scanning any creature you find to add them to your bestiary. Explore the wondrous outdoors and rummage through their derelict, steel and concrete underbellies. Just never miss the quota.

In short, it's a FPS game where you collect scraps in the planets that monsters are crawling around and sell them to your boss for the company.

## Target reader

Those who
- me in the future
- wanna know about unity hack

## Setting up Visual Studio project

Why it's a cinch to develop a hack of Unity? Essentially, by using C# as a language you're allowed to use all resources which the game uses in your hack code like classes, functions even member variables too as long as you configure your Visual Studio right.
It almost feels like you're using dynamic library of the game lol.

Right off the bat, create a C# Class Library project. Remember we're making internal hack.
Then, right click **References** on the solution explorer and click **Add Reference** -> **Browse** and go to root directory of the Lethal Company and find folder called "Lethal Company_Data/Managed". The "Managed" folder contains all the managed dll the game uses and is typically located under GAME_Data directory in case of other game too.

In the folder, there should be bunch of .dlls yet the ones we're interested in is what's called `Assenbly-CSharp.dll`, `Assembly-CSharp-firstpass.dll` and all the files starts their name with `Unity` and `UnityEngine`. I know it's tremendous amount, but add them all anyway.

![references](https://github.com/pseuxide/lethal_to_company/assets/33578715/2e407405-6208-41df-8cad-55e8c70c4d7b){: w="700" .normal}
_References window after added dlls mentioned above_


By now we added all we need which allow us to use all the fun stuff inside the game. The magic word `using UnityEngine;` gives us the power from now on.

## Probably an equivalent to dllmain... if you ask me

To perform its functionality after injection, define what's equivalent to dllmain in C++.
Following code is making GameObject, and adding component which is the body of our hack.
Remember the namespace, class name and function name will be required when we inject the produced dll. In our case, `lethal_to_company`, `loader`, `load`. I'll remind you about this in the later part.

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



## Hack code body

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

I'll show you the esp function and how I update the entity in real time later but let me show you Lethal Company's in-game entities `GrabbableObject[]` and `EnemyAI[]` first. Let's fire up dnSpy and take a look at in-game objects statically.

On dnSpy, hit **Edit -> Search Assembly** to search text from entire Unity assemblies of the game (I believe it technically means every managed dlls in same folder).
When I look up the word "enemy", one class appeared which stands out, `EnemyAI` which sounds promising. Click it and look at its overview.

![enemy search result](https://github.com/pseuxide/lethal_to_company/assets/33578715/7163b0b1-88e9-4e39-8035-cfff6ca0a54d){: .normal}
_"enemy" search result_

Indeed, the convincing symbol names are scattered around in the class such as `SetEnemyStunned` or `this.isEnemyDead`.

![enemy class](https://github.com/pseuxide/lethal_to_company/assets/33578715/2a8ce698-2c90-4e16-ae4e-223f6936d56e){: .normal}
_first view of EnemyAI class_

Ok EnemyAI's been found, then let's look for local player class. When you seach "Localplayer", 2 pure localplayer text come up which both of them seems the member variables of `HUDManager` and `SoundManager` class. This means you are able to obtain local player by `HUDManager.localPlayer` or `SoundManager.localPlayer`.

![local player](https://github.com/pseuxide/lethal_to_company/assets/33578715/46c47bff-c691-46f9-8972-d8f5319a6720){: .normal}
_the localPlayer member in HUDManager class_

Alright, now that you understand how to get the local player pointer, let's focus on the camera object. It's essential for calculating the object position for ESP. While it's commonly believed that `Camera.main` is the valid object used by many games, in this case, it's different. Neither `Camera.main` nor `Camera.current` are applicable.

After some test I found that the local player has an attached Camera class named `gameplayCamera` which seems promising.
Turns out this is a real camera used in the game.

![gameplay camera](https://github.com/pseuxide/lethal_to_company/assets/33578715/dfc9f119-3cbb-435b-a36c-a9f24074c3b4){: .normal}
_gameplayCamera class in the PlayerControllerB class (class of the local player)_

## How I update entities

In the last section we've found 3 entities we need (except grabbable object but it's same tedious thing).
Now we have to update entity's info within a each few frame to update position of the entity and such.

The main method is introduced by [this Guided Hacking post](https://guidedhacking.com/threads/how-to-hack-unity-mono-injection-codestage-anticheat.17915/). Apparently it's not performant way but frankly speaking I dont care.
Let's be lazy and take the easiest way. The function `FindObjectsOfType` automatically looks up every instances of the given type at runtime. Use this for EnemyAI and GrabbableObject.
But, in case of local player and camera, we can obtain them by `HUDManager.Instance.localPlayer` and `local_player.gameplayCamera`.

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

## Wall hack a.k.a ESP function

The code below is the esp function and some other utilities it uses.

- `world_to_screen` func calculates and translate world 3D position to screen 2D coordinate.
- `distance` func calculates distance between 2 objects.
- `esp` func draws box and line on your screen.

The sole interesting function here is `world_to_screen`. In terms of world to screen mechanism, people typically use `camera.WorldToScreenPoint` function which is predefined by Unity, but somewhat this game's WorldToScreenPoint function produces a bit off result from expecting coordinates. Frankly speaking I got stuck a few days due to this.

Fortunately, I found [this post](https://www.unknowncheats.me/forum/3921191-post32.html) on UC forum saying "use `camera.WorldToViewportPoint` instead". `WorldToViewportPoint` is similar to `WorldToScreenPoint`, but it produces normalized coordinates on the screen. Official document says

> Transforms position from world space into viewport space. Viewport space is normalized and relative to the camera. The bottom-left of the camera is (0,0); the top-right is (1,1). The z position is in world units from the camera.

Note that z axis refers to the depth from the camera. If z axis is positive value it means the object is in front of you and while not it's behind you.

Anyways, for this game `WorldToViewportPoint` works well as opposed to `WorldToScreenPoint`. Don't forget to multiply screen width and height to fit your resolution.

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

# Inject the dll

Once you built the dll, last thing you'd do is injecting it to the game.
Because the dll is managed, you have to use correct injector, not the one you've been using with C++ hack.
There're some options out there of which injector to use, but the best one is [SharpMonoInjector](https://github.com/warbler/SharpMonoInjector/releases).
Others doesn't work well but this one works nicely as of December 2023.

When you open it up, all the input must be blank.
So let's click "Refresh" button and let it find processes running with mono.
> If you're opening processes like Valorant or dnSpy which have some kind of "exclusive protection" when you press "Refresh", SharpMonoInjector will terminates immediately. Therefore make sure you close every those apps in advance.
{: .prompt-warning }

Secondly, click "..." to select dll that you want to inject, in my case it's called "lethal_to_company.dll".
Once you select the dll file it will automagically recognize the namespace you encapsulated your code in.

Lastly you fill the Class name and Method name which I as mentioned earlier part, are `loader` and `load`.
There you go, by pressing "Inject" button at the bottom, it will do its job after that.
You dont have to care about left pane of the injector UI when you inject.

![SharpMonoInjector](https://github.com/pseuxide/lethal_to_company/assets/33578715/74f91c58-354a-41ef-8c87-5b28ade033da){: .normal}
_SharpMonoInjector filled with all informations_

The final result looks like this.

![hack visual](https://github.com/pseuxide/lethal_to_company/assets/33578715/3cba1b1e-26a8-43ab-98f6-0a1f57900019){: .normal}
_resulting ESP. green indicates items and red indicates enemies_


## Conclusion

Honestly, I'm not gonna get along with C# any further. However I've been wanting to scratch the surface of Mono hacking once in my life. Indeed it was absolutely fresh experience from what I've been done with C++ and fun to manipulate game as if I modify game's source code directly.