using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;

namespace Harpoon.Core
{
	public class ModMetadata
	{
		[DisplayName("Enabled")]
		public bool IsEnabled { get; set; }

		[DisplayName("Name")]
		public string ModName { get; set; }

		[DisplayName("Version")]
		public string ModVersion { get; set; }

		[DisplayName("Description")]
		public string ModDescription { get; set; }

		[DisplayName("Author")]
		public string AuthorName { get; set; }

        [DisplayName("Game version")]
        public string GameVersion { get; set; }

        [DisplayName("Priority")]
        public int Priority { get; set; }

        public override string ToString()
        {
            return ModName + " version " + ModVersion + " by " + AuthorName + " (" + ModDescription + ") for game version " + GameVersion;
        }
	}

	public class Mod
	{
		public virtual ModMetadata Metadata =>
			new ModMetadata {
				AuthorName = "Your Name",
				ModDescription = "A new beginning to a wonderful mod!",
				ModName = "",
				ModVersion = "0.0.0"
			};

        public virtual void Initialize()
		{

		}
	}
}
