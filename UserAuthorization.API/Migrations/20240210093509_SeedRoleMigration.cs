using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace UserAuthorization.API.Migrations
{
    /// <inheritdoc />
    public partial class SeedRoleMigration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "550dad55-2334-4106-8705-d01f3cea6e6e", "1", "Admin", "Admin" },
                    { "5cb517aa-22ce-4a16-9deb-88a9ccc34806", "2", "User", "User" },
                    { "60dab46e-558d-4a6f-995d-baedb5e227cf", "3", "HR", "HR" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "550dad55-2334-4106-8705-d01f3cea6e6e");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5cb517aa-22ce-4a16-9deb-88a9ccc34806");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "60dab46e-558d-4a6f-995d-baedb5e227cf");
        }
    }
}
