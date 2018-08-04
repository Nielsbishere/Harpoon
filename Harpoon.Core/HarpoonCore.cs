using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

namespace Harpoon.Core
{
    
    public class HarpoonCore
    {

        private static Dictionary<string, Mod> mods = new Dictionary<string, Mod>();

        public static Mod GetMod(string name)
        {
            if (!mods.ContainsKey(name))
                return null;

            return mods[name];
        }

        public static void Initialize()
        {
            try
            {
                Console.WriteLine("Loading assemblies...");

                //These are just 'reflective' assemblies. They aren't executed.
                List<Assembly> modAssemblies = new List<Assembly>();

                //Check for dlls
                Console.WriteLine("Scanning " + Directory.GetCurrentDirectory() + "\\mods");

                string[] dirs = Directory.GetDirectories(Directory.GetCurrentDirectory() + "\\mods");

                List<Mod> modsPrioritized = new List<Mod>();

                //Categorize the dlls on if they have an Initializable
                foreach (string modDir in dirs)
                {
                    
                    //Load mods themselves

                    string[] modsPath = Directory.GetFiles(modDir, "*.dll");

                    Console.WriteLine("And mods: ");

                    foreach (string mod in modsPath)
                    {
                        Console.WriteLine("Checking " + mod);

                        try
                        {
                            //Check what category this belongs into

                            Assembly asm = Assembly.LoadFile(mod);
                            Type[] types = asm.GetTypes().Where(x => typeof(Mod).IsAssignableFrom(x)).ToArray();

                            if (types.Count() != 0)
                            {
                                modAssemblies.Add(asm);
                                Console.WriteLine("Found mod assembly " + mod);
                            }
                            
                            foreach (Type t in types)
                            {
                                Mod m = (Mod)Activator.CreateInstance(t);

                                if (m != null && m.Metadata.ModName == "")
                                    continue;

                                if(m == null || mods.ContainsKey(m.Metadata.ModName))
                                {
                                    Console.WriteLine("Couldn't load mod \"" + m.Metadata.ToString() + "\" it's already loaded or it is invalid");
                                    continue;
                                }

                                mods[m.Metadata.ModName] = m;
                                modsPrioritized.Add(m);

                            }
                        }
                        catch (ReflectionTypeLoadException e)
                        {
                            Console.WriteLine("Couldn't load dll (" + mod + "): ");

                            foreach (Exception ex in e.LoaderExceptions)
                                Console.WriteLine(ex.ToString());
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("Couldn't load dll (" + mod + "): " + e.ToString());
                        }
                    }
                }

                modsPrioritized = modsPrioritized.OrderBy(o => o.Metadata.Priority).ToList();

                foreach (Mod m in modsPrioritized)
                {
                    Console.WriteLine("Intializing \"" + m.Metadata.ToString() + "\"");
                    m.Initialize();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("ERROR: internal exception!\nCALL STACK:\n" + e.ToString());
            }
        }

    }

}