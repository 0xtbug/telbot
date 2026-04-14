package telkomsel

import (
	"context"
	"encoding/json"
	"fmt"

	"telkomsel-bot/model"
)

type BonusItem struct {
	Name           string `json:"name"`
	BucketDesc     string `json:"bucketdescription"`
	RemainingQuota      string  `json:"remainingquota"`
	RemainingQuotaValue float64 `json:"remainingquotaValue"`
	ExpiryDate          string  `json:"expirydate"`
	OrderID             string  `json:"order_id"`
}

type BonusGroup struct {
	Class       string      `json:"class"`
	TotalText   string      `json:"totalText"`
	TotalRecord int         `json:"totalRecord"`
	BonusList   []BonusItem `json:"bonusList"`
}

type QuotaData struct {
	UserBonuses []BonusGroup `json:"userBonuses"`
}

type QuotaInfo struct {
	Groups []QuotaGroup
}

type QuotaGroup struct {
	Class string
	Total string
	Items []QuotaItem
}

type QuotaItem struct {
	Name           string
	Remaining      string
	RemainingValue float64
	Expiry         string
	OrderID        string
}

func (c *Client) CheckQuota(ctx context.Context, session *model.Session) (*QuotaInfo, error) {
	body := map[string]interface{}{
		"isPrepaid": true,
		"location":  "",
		"roaming":   false,
	}

	resp, err := c.doPost(ctx, "/api/subscriber/v5/bonuses", session, body)
	if err != nil {
		return nil, err
	}

	if resp.Status != "00000" {
		return nil, fmt.Errorf("API error: %s", resp.Message)
	}

	var quotaData QuotaData
	if err := json.Unmarshal(resp.Data, &quotaData); err != nil {
		return nil, fmt.Errorf("parse quota data: %w", err)
	}

	info := &QuotaInfo{}
	for _, bonus := range quotaData.UserBonuses {
		group := QuotaGroup{
			Class: bonus.Class,
			Total: bonus.TotalText,
		}
		for _, item := range bonus.BonusList {
			name := item.Name
			if name == "" {
				name = item.BucketDesc
			}
			group.Items = append(group.Items, QuotaItem{
				Name:           name,
				Remaining:      item.RemainingQuota,
				RemainingValue: item.RemainingQuotaValue,
				Expiry:         item.ExpiryDate,
				OrderID:        item.OrderID,
			})
		}
		info.Groups = append(info.Groups, group)
	}

	return info, nil
}

func FormatQuota(info *QuotaInfo) string {
	if info == nil || len(info.Groups) == 0 {
		return "📊 No quota data available."
	}

	result := "📊 *Telkomsel Quota Info*\n\n"
	for _, g := range info.Groups {
		result += fmt.Sprintf("📦 *%s* — %s\n", g.Class, g.Total)
		for _, item := range g.Items {
			result += fmt.Sprintf("  • %s: *%s* (exp: %s)\n", item.Name, item.Remaining, item.Expiry)
		}
		result += "\n"
	}

	return result
}
